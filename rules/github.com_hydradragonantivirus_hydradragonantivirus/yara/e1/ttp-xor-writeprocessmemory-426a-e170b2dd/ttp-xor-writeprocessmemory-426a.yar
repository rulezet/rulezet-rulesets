rule TTP_XOR_WriteProcessMemory_426a {
  strings:
    $key_426a = { 15 18 [2] 27 3a [2] 21 0f [2] 0f 0f [2] 30 13 }

  condition:
    any of them
}