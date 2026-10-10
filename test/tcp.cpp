#define BOOST_TEST_MODULE TcpTest

#include <boost/test/tools/old/interface.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/test/unit_test_suite.hpp>

#include <cstdint>
#include <iostream>

#include "include/Socket.hpp"
#include "include/Tcp.hpp"

BOOST_AUTO_TEST_CASE(test_tcp)
{
  HttpServer::Tcp tcp{};

  try
  {
    tcp.wait_for_connection(); // wait for SYN -> REPLY with SYN + ACK
    tcp.wait_for_connection(); // wait for ACK.
  }
  catch(std::exception &e)
  {
    BOOST_CHECK_EQUAL(e.what(), ""); // so it prints in red
    BOOST_REQUIRE(false);            // so it finises
  }
}
