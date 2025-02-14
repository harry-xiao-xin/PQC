#include <pybind11/pybind11.h>
#include "ml_kem/ml_kem_wrapper.hpp"

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)
namespace py = pybind11;
PYBIND11_MODULE(PQC_PYTHON, m) {
    m.doc() = R"pbdoc(
        PQC_PYTHON: PQC library
        -----------------------

        .. currentmodule:: PQC_PYTHON

        .. autosummary::
           :toctree: _generate

           ml_kem_512_keygen
           ml_kem_512_encapsulate
           ml_kem_512_decapsulate

           ml_kem_768_keygen
           ml_kem_768_encapsulate
           ml_kem_768_decapsulate

           ml_kem_1024_keygen
           ml_kem_1024_encapsulate
           ml_kem_1024_decapsulate
    )pbdoc";
    m.def("ml_kem_512_keygen", &ml_kem::ml_kem_512_keygen, R"pbdoc(
         /**
         * generate ml_kem_512 public key and secret key
         * @return public key and secret key
         */
    )pbdoc");
    m.def("ml_kem_512_encapsulate", &ml_kem::ml_kem_512_encapsulate, R"pbdoc(
        /**
         * generate cipher and shared secret text from public key
         * @param pubkey public key
         * @return cipher and shared secret
         */
    )pbdoc");
    m.def("ml_kem_512_decapsulate", &ml_kem::ml_kem_512_decapsulate, R"pbdoc(
       /**
         * recover shared_secret from secret key and cipher
         * @param seckey secret key
         * @param cipher cipher
         * @return shared_secret
         */
    )pbdoc");

    m.def("ml_kem_768_keygen", &ml_kem::ml_kem_768_keygen, R"pbdoc(
         /**
         * generate ml_kem_512 public key and secret key
         * @return public key and secret key
         */
    )pbdoc");
    m.def("ml_kem_768_encapsulate", &ml_kem::ml_kem_768_encapsulate, R"pbdoc(
        /**
         * generate cipher and shared secret text from public key
         * @param pubkey public key
         * @return cipher and shared secret
         */
    )pbdoc");
    m.def("ml_kem_768_decapsulate", &ml_kem::ml_kem_768_decapsulate, R"pbdoc(
       /**
         * recover shared_secret from secret key and cipher
         * @param seckey secret key
         * @param cipher cipher
         * @return shared_secret
         */
    )pbdoc");

    m.def("ml_kem_1024_keygen", &ml_kem::ml_kem_1024_keygen, R"pbdoc(
         /**
         * generate ml_kem_512 public key and secret key
         * @return public key and secret key
         */
    )pbdoc");
    m.def("ml_kem_1024_encapsulate", &ml_kem::ml_kem_1024_encapsulate, R"pbdoc(
        /**
         * generate cipher and shared secret text from public key
         * @param pubkey public key
         * @return cipher and shared secret
         */
    )pbdoc");
    m.def("ml_kem_1024_decapsulate", &ml_kem::ml_kem_1024_decapsulate, R"pbdoc(
       /**
         * recover shared_secret from secret key and cipher
         * @param seckey secret key
         * @param cipher cipher
         * @return shared_secret
         */
    )pbdoc");

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}