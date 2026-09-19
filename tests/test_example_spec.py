from ghost.spec.loader import load_spec


def test_example_spec_loads_and_marks_admin_refund_destructive():
    spec = load_spec("specs/example_ecommerce.json")
    assert spec.states["ADMIN_REFUND"].destructive is True
