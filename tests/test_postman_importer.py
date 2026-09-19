from ghost.spec.importers.postman import import_postman


def _collection() -> dict:
    return {
        "info": {"name": "orders-api"},
        "variable": [{"key": "base_url", "value": "https://api.example.test"}],
        "item": [
            {
                "name": "Get Order",
                "request": {
                    "method": "GET",
                    "url": {"raw": "{{base_url}}/orders/:id"},
                    "header": [
                        {"key": "Authorization", "value": "Bearer secret"},
                        {"key": "Accept", "value": "application/json"},
                    ],
                },
            },
            {
                "name": "Auth folder",
                "item": [
                    {
                        "name": "Create Order",
                        "request": {
                            "method": "POST",
                            "url": {"raw": "{{base_url}}/orders"},
                            "body": {"mode": "raw", "raw": '{"item_id": 1}'},
                        },
                    }
                ],
            },
        ],
    }


def test_flattens_nested_folders_and_templatizes_path_vars():
    spec = import_postman(_collection())
    assert set(spec.states) == {"GET_ORDER", "CREATE_ORDER"}
    assert spec.states["GET_ORDER"].url == "https://api.example.test/orders/{id}"


def test_redacts_authorization_header_and_parses_body():
    spec = import_postman(_collection())
    assert "Authorization" not in spec.states["GET_ORDER"].headers
    assert spec.states["CREATE_ORDER"].default_data == {"item_id": 1}
