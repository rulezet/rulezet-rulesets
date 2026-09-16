rule TTP_XOR_WriteProcessMemory_ee7c {
  strings:
    $key_ee7c = { b9 0e [2] 8b 2c [2] 8d 19 [2] a3 19 [2] 9c 05 }

  condition:
    any of them
}