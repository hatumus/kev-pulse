import os
import tempfile
import unittest
from unittest.mock import patch

import yaml

from kev_pulse.config import ConfigError, load_config


class ConfigLoadTest(unittest.TestCase):
    def _write_yaml(self, data):
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh)
        self.addCleanup(os.remove, path)
        return path

    # -- single-backend auto-detection -----------------------------------

    def test_tvm_only_becomes_primary_no_yaml_picker_needed(self):
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_TVM_ONLY_AK",
                        "secret_key_env": "T_TVM_ONLY_SK",
                    },
                }
            }
        )
        with patch.dict(
            os.environ,
            {"T_TVM_ONLY_AK": "ak", "T_TVM_ONLY_SK": "sk"},
        ):
            cfg = load_config(path)
        self.assertEqual(cfg.backend.type, "tvm")
        self.assertEqual(cfg.backend.access_key, "ak")
        self.assertIsNone(cfg.secondary_backend)

    def test_sc_only_via_secondary_block_becomes_primary(self):
        # Mirrors a customer who only has Security Center: the primary
        # `backend:` block is left with no credentials (as shipped), and
        # only `backend.secondary` (type: sc) is filled in. That single
        # configured backend must become primary automatically -- no YAML
        # picker, no KEVPULSE_BACKEND_TYPE needed.
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {},
                    "secondary": {
                        "type": "sc",
                        "url_env": "T_SC_ONLY_URL",
                        "auth": {
                            "username_env": "T_SC_ONLY_USER",
                            "password_env": "T_SC_ONLY_PASS",
                        },
                    },
                }
            }
        )
        with patch.dict(
            os.environ,
            {
                "T_SC_ONLY_URL": "https://tsc.example.com",
                "T_SC_ONLY_USER": "alice",
                "T_SC_ONLY_PASS": "secret",
            },
        ):
            cfg = load_config(path)
        self.assertEqual(cfg.backend.type, "sc")
        self.assertEqual(cfg.backend.username, "alice")
        self.assertEqual(cfg.backend.url, "https://tsc.example.com")
        self.assertIsNone(cfg.secondary_backend)

    def test_neither_backend_configured_raises_with_both_reasons(self):
        path = self._write_yaml({"backend": {"type": "tvm", "auth": {}}})
        with self.assertRaises(ConfigError) as ctx:
            load_config(path)
        self.assertIn("No usable Tenable backend is configured", str(ctx.exception))

    def test_primary_env_reference_missing_is_non_fatal_when_secondary_ok(self):
        # Regression test for the ~1.5-day outage: a dangling `_env`
        # reference in one backend block must never take down a server
        # that has a working secondary backend.
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_DANGLING_AK",  # never set below
                        "secret_key_env": "T_DANGLING_SK",
                    },
                    "secondary": {
                        "type": "sc",
                        "url": "https://tsc.example.com",
                        "auth": {
                            "username_env": "T_DANGLING_USER",
                            "password_env": "T_DANGLING_PASS",
                        },
                    },
                }
            }
        )
        with patch.dict(
            os.environ,
            {"T_DANGLING_USER": "alice", "T_DANGLING_PASS": "secret"},
        ):
            cfg = load_config(path)
        self.assertEqual(cfg.backend.type, "sc")
        self.assertIsNone(cfg.secondary_backend)

    # -- both backends configured: default / override selection ----------

    def test_both_configured_no_override_uses_backend_type_default(self):
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_BOTH_AK",
                        "secret_key_env": "T_BOTH_SK",
                    },
                    "secondary": {
                        "type": "sc",
                        "url": "https://tsc.example.com",
                        "auth": {
                            "username_env": "T_BOTH_USER",
                            "password_env": "T_BOTH_PASS",
                        },
                    },
                },
                "scan": {
                    "policy_template_id": {"tvm": "t-uuid", "sc": "1"},
                },
            }
        )
        with patch.dict(
            os.environ,
            {
                "T_BOTH_AK": "ak",
                "T_BOTH_SK": "sk",
                "T_BOTH_USER": "alice",
                "T_BOTH_PASS": "secret",
            },
        ):
            cfg = load_config(path)
        self.assertEqual(cfg.backend.type, "tvm")
        self.assertIsNotNone(cfg.secondary_backend)
        self.assertEqual(cfg.secondary_backend.type, "sc")

    def test_both_configured_explicit_override_picks_secondary(self):
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_OVR_AK",
                        "secret_key_env": "T_OVR_SK",
                    },
                    "secondary": {
                        "type": "sc",
                        "url": "https://tsc.example.com",
                        "auth": {
                            "username_env": "T_OVR_USER",
                            "password_env": "T_OVR_PASS",
                        },
                    },
                },
                "scan": {
                    "policy_template_id": {"tvm": "t-uuid", "sc": "1"},
                },
            }
        )
        with patch.dict(
            os.environ,
            {
                "T_OVR_AK": "ak",
                "T_OVR_SK": "sk",
                "T_OVR_USER": "alice",
                "T_OVR_PASS": "secret",
                "KEVPULSE_BACKEND_TYPE": "sc",
            },
        ):
            cfg = load_config(path)
        self.assertEqual(cfg.backend.type, "sc")
        self.assertEqual(cfg.secondary_backend.type, "tvm")

    def test_override_for_backend_with_no_credentials_raises(self):
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_BADOVR_AK",
                        "secret_key_env": "T_BADOVR_SK",
                    },
                }
            }
        )
        with patch.dict(
            os.environ,
            {
                "T_BADOVR_AK": "ak",
                "T_BADOVR_SK": "sk",
                "KEVPULSE_BACKEND_TYPE": "sc",
            },
        ):
            with self.assertRaises(ConfigError) as ctx:
                load_config(path)
        self.assertIn("KEVPULSE_BACKEND_TYPE", str(ctx.exception))

    # -- the packaged-extension blank-field bug ---------------------------

    def test_unsubstituted_template_string_override_is_ignored_single_backend(self):
        # This is the exact crash the packaged Claude Desktop extension
        # produced: when the optional "Primary backend" user_config field
        # is left blank, Claude Desktop passes through the literal,
        # unsubstituted text "${user_config.primary_backend}" as the env
        # var's value instead of an empty string. That must never crash a
        # server that otherwise has a perfectly usable single backend.
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_TMPL_AK",
                        "secret_key_env": "T_TMPL_SK",
                    },
                }
            }
        )
        with patch.dict(
            os.environ,
            {
                "T_TMPL_AK": "ak",
                "T_TMPL_SK": "sk",
                "KEVPULSE_BACKEND_TYPE": "${user_config.primary_backend}",
            },
        ):
            cfg = load_config(path)  # must not raise
        self.assertEqual(cfg.backend.type, "tvm")

    def test_unsubstituted_template_string_override_is_ignored_both_backends(self):
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_TMPL2_AK",
                        "secret_key_env": "T_TMPL2_SK",
                    },
                    "secondary": {
                        "type": "sc",
                        "url": "https://tsc.example.com",
                        "auth": {
                            "username_env": "T_TMPL2_USER",
                            "password_env": "T_TMPL2_PASS",
                        },
                    },
                },
                "scan": {
                    "policy_template_id": {"tvm": "t-uuid", "sc": "1"},
                },
            }
        )
        with patch.dict(
            os.environ,
            {
                "T_TMPL2_AK": "ak",
                "T_TMPL2_SK": "sk",
                "T_TMPL2_USER": "alice",
                "T_TMPL2_PASS": "secret",
                "KEVPULSE_BACKEND_TYPE": "${user_config.primary_backend}",
            },
        ):
            cfg = load_config(path)  # must not raise
        # falls through to the backend.type default, same as no override at all
        self.assertEqual(cfg.backend.type, "tvm")

    def test_empty_string_override_is_ignored(self):
        # The plain "unset" case (no env var, or set to "") must also be
        # treated as no override -- covered separately from the template-
        # string case since it takes a different path through the guard.
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_EMPTY_AK",
                        "secret_key_env": "T_EMPTY_SK",
                    },
                }
            }
        )
        with patch.dict(
            os.environ,
            {"T_EMPTY_AK": "ak", "T_EMPTY_SK": "sk", "KEVPULSE_BACKEND_TYPE": ""},
        ):
            cfg = load_config(path)
        self.assertEqual(cfg.backend.type, "tvm")

    # -- secondary-same-type-as-primary is ignored, not fatal -------------

    def test_secondary_same_type_as_primary_is_ignored(self):
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_DUP_AK",
                        "secret_key_env": "T_DUP_SK",
                    },
                    "secondary": {
                        "type": "tvm",
                        "auth": {
                            "access_key_env": "T_DUP_AK2",
                            "secret_key_env": "T_DUP_SK2",
                        },
                    },
                }
            }
        )
        with patch.dict(
            os.environ,
            {
                "T_DUP_AK": "ak",
                "T_DUP_SK": "sk",
                "T_DUP_AK2": "ak2",
                "T_DUP_SK2": "sk2",
            },
        ):
            cfg = load_config(path)
        self.assertEqual(cfg.backend.type, "tvm")
        self.assertIsNone(cfg.secondary_backend)

    # -- scan.policy_template_id validation --------------------------------

    def test_single_string_policy_template_id_with_both_backends_raises(self):
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_POL_AK",
                        "secret_key_env": "T_POL_SK",
                    },
                    "secondary": {
                        "type": "sc",
                        "url": "https://tsc.example.com",
                        "auth": {
                            "username_env": "T_POL_USER",
                            "password_env": "T_POL_PASS",
                        },
                    },
                },
                "scan": {"policy_template_id": "1"},
            }
        )
        with patch.dict(
            os.environ,
            {
                "T_POL_AK": "ak",
                "T_POL_SK": "sk",
                "T_POL_USER": "alice",
                "T_POL_PASS": "secret",
            },
        ):
            with self.assertRaises(ConfigError) as ctx:
                load_config(path)
        self.assertIn("policy_template_id", str(ctx.exception))

    def test_single_string_policy_template_id_with_one_backend_is_fine(self):
        path = self._write_yaml(
            {
                "backend": {
                    "type": "tvm",
                    "auth": {
                        "access_key_env": "T_POL2_AK",
                        "secret_key_env": "T_POL2_SK",
                    },
                },
                "scan": {"policy_template_id": "1"},
            }
        )
        with patch.dict(
            os.environ, {"T_POL2_AK": "ak", "T_POL2_SK": "sk"}
        ):
            cfg = load_config(path)
        self.assertEqual(cfg.scan.policy_template_id, {"tvm": "1"})


if __name__ == "__main__":
    unittest.main()
