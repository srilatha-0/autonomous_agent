from tools import (
    t1, t2, t3, t4,
    reset_tool_invocation_order,
    get_tool_invocation_order
)

ip_address = "185.220.101.45"

tests = [
    ("T1", t1, ip_address),
    ("T2", t2, ip_address),
    ("T3", t3, ip_address),
    ("T4", t4, f"Threat intelligence context for IP {ip_address}"),
]

for name, tool, argument in tests:
    print("\n" + "=" * 50)
    print(f"Testing {name}")
    print("=" * 50)

    reset_tool_invocation_order()

    try:
        result = tool.run(argument)
        print("\nTool returned:")
        print(result)
    except Exception as e:
        print("\nExecution exception:", repr(e))

    actual_order = get_tool_invocation_order()
    print("\nRecorded invocation:")
    print(actual_order if actual_order else "NOT RECORDED")