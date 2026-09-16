rule TTP_XOR_WriteProcessMemory_87d8 {
  strings:
    $key_87d8 = { d0 aa [2] e2 88 [2] e4 bd [2] ca bd [2] f5 a1 }

  condition:
    any of them
}