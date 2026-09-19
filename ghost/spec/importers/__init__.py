"""
Spec bootstrapping importers.

These convert existing artifacts from an engagement (an OpenAPI/Swagger
doc, a recorded Burp Suite or ZAP proxy history, a Postman collection)
into a draft ApplicationSpec, so operators aren't hand-writing every
state and transition from scratch. The output is always a *draft* —
`auth_context`, `entry_states`, and the legal `transitions` graph
almost always need a human pass, since intended business-flow order
isn't fully recoverable from traffic/schema alone.
"""
