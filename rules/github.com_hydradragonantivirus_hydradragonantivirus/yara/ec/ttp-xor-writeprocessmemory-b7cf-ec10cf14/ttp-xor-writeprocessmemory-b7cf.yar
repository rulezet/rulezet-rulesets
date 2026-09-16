rule TTP_XOR_WriteProcessMemory_b7cf {
  strings:
    $key_b7cf = { e0 bd [2] d2 9f [2] d4 aa [2] fa aa [2] c5 b6 }

  condition:
    any of them
}