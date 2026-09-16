rule TTP_XOR_WriteProcessMemory_b1cf {
  strings:
    $key_b1cf = { e6 bd [2] d4 9f [2] d2 aa [2] fc aa [2] c3 b6 }

  condition:
    any of them
}