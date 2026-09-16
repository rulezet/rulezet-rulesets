rule TTP_XOR_WriteProcessMemory_7949 {
  strings:
    $key_7949 = { 2e 3b [2] 1c 19 [2] 1a 2c [2] 34 2c [2] 0b 30 }

  condition:
    any of them
}