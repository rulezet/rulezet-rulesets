rule TTP_XOR_WriteProcessMemory_906a {
  strings:
    $key_906a = { c7 18 [2] f5 3a [2] f3 0f [2] dd 0f [2] e2 13 }

  condition:
    any of them
}