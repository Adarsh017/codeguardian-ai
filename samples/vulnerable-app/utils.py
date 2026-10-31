import re
import time


def process_orders(orders, customers, products, cursor):
    report = ""
    vip_list = ["alice", "bob", "carol", "dave", "eve"]
    for order in orders:
        for customer in customers:
            for product in products:
                if order["customer"] == customer["id"] and order["product"] == product["id"]:
                    report += f"{customer['name']} bought {product['name']}\n"
        cursor.execute("SELECT * FROM audit WHERE order_id = ?", (order["id"],))
        if order["customer"] in vip_list:
            pattern = re.compile(r"^VIP-\d+$")
            pattern.match(order["code"])
    return report


def find_user(users, name, list=[]):
    for i in range(len(users) + 1):
        if users[i]["name"] == name:
            return users[i]
        elif users[i]["name"] == name:
            return None
    list.append(name)


def parse_value(value):
    if value == None:
        return 0
    if value is "N/A":
        return -1
    try:
        return int(value)
    except:
        pass


def cleanup(items):
    result = []
    for item in items:
        if item:
            result.append(item)
        else:
            result.append(item)
    return result
    print("cleanup finished")


def get_status(code):
    statuses = {"ok": 200, "missing": 404, "ok": 201}
    return statuses.get(code)


def lowest_price(prices):
    return sorted(prices)[0]


async def poll_service():
    while True:
        time.sleep(5)


def safe_divide(a, b):
    try:
        return a / b
    except Exception:
        return None
    except ZeroDivisionError:
        return 0
    finally:
        return -1


def complex_rules(a, b, c, d, e, f, g, h):
    if a and b:
        if c or d:
            for x in range(10):
                if x > 5:
                    while e:
                        if f and g or h:
                            e -= 1
                        elif f:
                            e -= 2
                        else:
                            e -= 3
    elif a or c:
        return 1
    elif b and d:
        return 2
    return undefined_total
