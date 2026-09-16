rule TTP_XOR_WriteProcessMemory_3e2f {
  strings:
    $key_3e2f = { 69 5d [2] 5b 7f [2] 5d 4a [2] 73 4a [2] 4c 56 }

  condition:
    any of them
}