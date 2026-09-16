rule TTP_XOR_WriteProcessMemory_213f {
  strings:
    $key_213f = { 76 4d [2] 44 6f [2] 42 5a [2] 6c 5a [2] 53 46 }

  condition:
    any of them
}