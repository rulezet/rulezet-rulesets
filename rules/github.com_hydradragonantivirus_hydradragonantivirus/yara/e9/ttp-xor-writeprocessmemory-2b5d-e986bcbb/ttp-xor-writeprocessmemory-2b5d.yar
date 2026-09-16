rule TTP_XOR_WriteProcessMemory_2b5d {
  strings:
    $key_2b5d = { 7c 2f [2] 4e 0d [2] 48 38 [2] 66 38 [2] 59 24 }

  condition:
    any of them
}