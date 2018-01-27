PROJECT = ecdaa-erlang

c_src/ecdaa:
	cd c_src ; git clone -b master https://github.com/xaptum/ecdaa

c_src/ecdaa/milagro-crypto-c : c_src/ecdaa
	cd c_src/ecdaa ; git clone -b headers-under-directory https://github.com/zanebeckwith/milagro-crypto-c

compile:    c_src/ecdaa/milagro-crypto-c
	cd c_src/ecdaa/milagro-crypto-c ; mkdir -p build ; mkdir -p install ; cd build ; cmake .. -DAMCL_CURVE=FP256BN -DBUILD_SHARED_LIBS=Off -DCMAKE_POSITION_INDEPENDENT_CODE=On ; cmake --build . ; make install
	cd c_src ; mkdir -p build ; cd build ; cmake .. -DECDAA_TPM_SUPPORT=OFF ; cmake --build . ; cd ../..

clean:
	rm -rf c_src/build ; rm -rf c_src/ecdaa
