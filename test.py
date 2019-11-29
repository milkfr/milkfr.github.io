import threading
lock = threading.Lock()

n = [0]


def foo():
    with lock:
        for _ in range(1000000):
            n[0] += 1


threads = []

for i in range(50):
    t = threading.Thread(target=foo)
    threads.append(t)

for t in threads:
    t.start()

for t in threads:
    t.join()

print(n)
