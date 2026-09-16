rule TTP_XOR_WriteProcessMemory_593f {
  strings:
    $key_593f = { 0e 4d [2] 3c 6f [2] 3a 5a [2] 14 5a [2] 2b 46 }

  condition:
    any of them
}