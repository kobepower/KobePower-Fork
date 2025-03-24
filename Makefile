CFLAGS += -DPYTHON_WRAPPER

python_bindings:
	swig -python kobe_wrapper.i
	gcc -shared kobe_wrapper_wrap.c -o _kobe.so $(PROXMARK_CFLAGS) -I/usr/include/python3.12 -lpython3.12
