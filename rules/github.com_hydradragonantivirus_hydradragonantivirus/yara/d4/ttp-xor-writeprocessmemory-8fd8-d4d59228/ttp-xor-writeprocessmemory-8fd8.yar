rule TTP_XOR_WriteProcessMemory_8fd8 {
  strings:
    $key_8fd8 = { d8 aa [2] ea 88 [2] ec bd [2] c2 bd [2] fd a1 }

  condition:
    any of them
}