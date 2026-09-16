rule TTP_XOR_WriteProcessMemory_410a {
  strings:
    $key_410a = { 16 78 [2] 24 5a [2] 22 6f [2] 0c 6f [2] 33 73 }

  condition:
    any of them
}