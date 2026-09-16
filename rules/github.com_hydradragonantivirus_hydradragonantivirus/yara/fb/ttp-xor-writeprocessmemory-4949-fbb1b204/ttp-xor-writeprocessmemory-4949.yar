rule TTP_XOR_WriteProcessMemory_4949 {
  strings:
    $key_4949 = { 1e 3b [2] 2c 19 [2] 2a 2c [2] 04 2c [2] 3b 30 }

  condition:
    any of them
}