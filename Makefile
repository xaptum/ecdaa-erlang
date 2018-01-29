PROJECT = ecdaa-erlang

.PHONY: compile

compile:
	cd c_src ; mkdir -p build ; cd build ; cmake .. -DCMAKE_INSTALL_PREFIX=$(shell pwd)/../../priv ; cmake --build . ; sudo make install ; cd ../..
	rebar3 compile

clean:
	rm -rf _build
