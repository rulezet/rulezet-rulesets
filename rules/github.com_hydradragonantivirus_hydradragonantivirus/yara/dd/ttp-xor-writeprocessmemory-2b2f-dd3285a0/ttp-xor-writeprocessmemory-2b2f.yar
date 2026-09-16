rule TTP_XOR_WriteProcessMemory_2b2f {
  strings:
    $key_2b2f = { 7c 5d [2] 4e 7f [2] 48 4a [2] 66 4a [2] 59 56 }

  condition:
    any of them
}