PROJECT = ecdaa-erlang
REBAR = rebar3

.PHONY: compile

compile:
	cd c_src ; mkdir -p build ; cd build ; cmake .. -DCMAKE_INSTALL_PREFIX=$(shell pwd)/../../priv ; cmake --build . ; sudo make install ; cd ../..
	$(REBAR) compile

test: compile
	$(REBAR) eunit

clean:
	rm -rf _build
