from httpie.capability_manager import serialize_capability_param_text


def test_serialize_capability_params_uses_semicolon_between_pairs():
    params = {
        "paramA": ["val1", "val2", "val3"],
        "paramB": "val4",
    }
    text = serialize_capability_param_text(params, ordered_keys=["paramA", "paramB"])
    assert text == "paramA=val1,val2,val3;paramB=val4"


def test_serialize_capability_params_skips_capability_key():
    params = {
        "capability": {"sid": "x"},
        "host": "127.0.0.1",
        "permissions": [1, 4],
    }
    text = serialize_capability_param_text(params, ordered_keys=["capability", "host", "permissions"])
    assert text == "host=127.0.0.1;permissions=1,4"
