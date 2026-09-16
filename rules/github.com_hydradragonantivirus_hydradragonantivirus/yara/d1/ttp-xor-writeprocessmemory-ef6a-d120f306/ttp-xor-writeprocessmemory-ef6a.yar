rule TTP_XOR_WriteProcessMemory_ef6a {
  strings:
    $key_ef6a = { b8 18 [2] 8a 3a [2] 8c 0f [2] a2 0f [2] 9d 13 }

  condition:
    any of them
}