rule TTP_XOR_WriteProcessMemory_e17a {
  strings:
    $key_e17a = { b6 08 [2] 84 2a [2] 82 1f [2] ac 1f [2] 93 03 }

  condition:
    any of them
}