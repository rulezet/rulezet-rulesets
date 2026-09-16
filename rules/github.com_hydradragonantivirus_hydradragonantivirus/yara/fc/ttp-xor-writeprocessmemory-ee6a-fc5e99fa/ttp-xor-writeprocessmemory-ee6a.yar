rule TTP_XOR_WriteProcessMemory_ee6a {
  strings:
    $key_ee6a = { b9 18 [2] 8b 3a [2] 8d 0f [2] a3 0f [2] 9c 13 }

  condition:
    any of them
}