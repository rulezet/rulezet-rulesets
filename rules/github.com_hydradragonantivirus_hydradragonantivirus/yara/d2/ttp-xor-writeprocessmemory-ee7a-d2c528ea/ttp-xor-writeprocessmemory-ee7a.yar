rule TTP_XOR_WriteProcessMemory_ee7a {
  strings:
    $key_ee7a = { b9 08 [2] 8b 2a [2] 8d 1f [2] a3 1f [2] 9c 03 }

  condition:
    any of them
}