rule TTP_XOR_WriteProcessMemory_ee0f {
  strings:
    $key_ee0f = { b9 7d [2] 8b 5f [2] 8d 6a [2] a3 6a [2] 9c 76 }

  condition:
    any of them
}