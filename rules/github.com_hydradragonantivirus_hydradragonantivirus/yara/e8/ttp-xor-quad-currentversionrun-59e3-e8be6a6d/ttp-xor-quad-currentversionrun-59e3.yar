rule TTP_XOR_QUAD_CurrentVersionRun_59e3 {
  strings:
    $key_59e3 = { 0a 8c [2] 2e 82 [2] 05 ae [2] 2b 8c [2] 3f 97 [2] 30 8d [2] 2e 90 [2] 2c 91 [2] 37 97 [2] 2b 90 [2] 37 bf }

  condition:
    any of them
}