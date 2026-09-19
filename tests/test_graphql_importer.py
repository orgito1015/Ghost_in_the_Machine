from ghost.spec.importers.graphql import import_graphql_introspection, import_graphql_sdl


def test_sdl_import_builds_query_and_mutation_states():
    sdl = """
    type Query {
      me: User
      order(id: ID!): Order
    }

    type Mutation {
      createOrder(itemId: ID!, qty: Int!): Order
    }
    """
    spec = import_graphql_sdl(sdl, endpoint="https://api.example.test/graphql")

    assert set(spec.states) == {"me", "order", "createOrder"}
    create = spec.states["createOrder"]
    assert create.url == "https://api.example.test/graphql"
    assert create.method.value == "POST"
    assert "mutation" in create.default_data["query"]
    assert set(create.default_data["variables"]) == {"itemId", "qty"}
    assert create.default_data["variables"]["qty"] == 0  # Int placeholder


def test_sdl_import_with_no_args_field():
    sdl = "type Query { ping: String }"
    spec = import_graphql_sdl(sdl, endpoint="https://api.example.test/graphql")
    assert spec.states["ping"].default_data["variables"] == {}
    assert "query" in spec.states["ping"].default_data["query"]


def test_sdl_import_raises_on_no_operations_found():
    import pytest

    with pytest.raises(ValueError):
        import_graphql_sdl("type User { id: ID }", endpoint="https://x.test/graphql")


def test_introspection_import_builds_states_with_typed_placeholders():
    result = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "name": "Query",
                        "fields": [
                            {"name": "me", "args": []},
                        ],
                    },
                    {
                        "name": "Mutation",
                        "fields": [
                            {
                                "name": "redeemCoupon",
                                "args": [
                                    {"name": "code", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}},
                                ],
                            },
                        ],
                    },
                ],
            }
        }
    }
    spec = import_graphql_introspection(result, endpoint="https://api.example.test/graphql")

    assert set(spec.states) == {"me", "redeemCoupon"}
    redeem = spec.states["redeemCoupon"]
    assert redeem.default_data["variables"] == {"code": ""}
    assert "$code: String!" in redeem.default_data["query"]
