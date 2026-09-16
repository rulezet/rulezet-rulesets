rule TTP_XOR_WriteProcessMemory_b53a {
  strings:
    $key_b53a = { e2 48 [2] d0 6a [2] d6 5f [2] f8 5f [2] c7 43 }

  condition:
    any of them
}