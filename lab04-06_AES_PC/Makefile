all:
	g++ aestest4_simple_version.cpp -o aestest4_simple_version.out
	g++ aestest5_optimized_no_tbox.cpp -o aestest5_optimized_no_tbox.out
	g++ aestest5_optimized_with_tbox.cpp -o aestest5_optimized_with_tbox.out
	g++ -maes aestest6_ni.cpp -o aestest6_ni.out
	g++ -maes aestest6_ni_on_the_fly.cpp -o aestest6_ni_on_the_fly.out
	g++ -Ofast aestest5_optimized_no_tbox.cpp -o ofast-aestest5_optimized_no_tbox.out
	g++ -Ofast aestest5_optimized_with_tbox.cpp -o ofast-aestest5_optimized_with_tbox.out
	g++ -Ofast -maes aestest6_ni.cpp -o ofast-aestest6_ni.out
	g++ -Ofast -maes aestest6_ni_on_the_fly.cpp -o ofast-aestest6_ni_on_the_fly.out

run:
	-./aestest4_simple_version.out
	-./aestest5_optimized_no_tbox.out $(arg) ||:
	-./aestest5_optimized_with_tbox.out $(arg) ||:
	-./aestest6_ni.out $(arg) ||:
	-./aestest6_ni_on_the_fly.out $(arg) ||:
	-./ofast-aestest5_optimized_no_tbox.out $(arg) ||:
	-./ofast-aestest5_optimized_with_tbox.out $(arg) ||:
	-./ofast-aestest6_ni.out $(arg) ||:
	-./ofast-aestest6_ni_on_the_fly.out $(arg) ||:

