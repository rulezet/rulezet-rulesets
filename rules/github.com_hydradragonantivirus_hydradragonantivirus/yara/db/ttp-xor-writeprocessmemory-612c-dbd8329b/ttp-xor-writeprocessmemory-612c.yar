rule TTP_XOR_WriteProcessMemory_612c {
  strings:
    $key_612c = { 36 5e [2] 04 7c [2] 02 49 [2] 2c 49 [2] 13 55 }

  condition:
    any of them
}