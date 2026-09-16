rule TTP_XOR_WriteProcessMemory_177a {
  strings:
    $key_177a = { 40 08 [2] 72 2a [2] 74 1f [2] 5a 1f [2] 65 03 }

  condition:
    any of them
}