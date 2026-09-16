rule TTP_XOR_WriteProcessMemory_f87c {
  strings:
    $key_f87c = { af 0e [2] 9d 2c [2] 9b 19 [2] b5 19 [2] 8a 05 }

  condition:
    any of them
}