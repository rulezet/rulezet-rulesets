rule TTP_XOR_WriteProcessMemory_94cf {
  strings:
    $key_94cf = { c3 bd [2] f1 9f [2] f7 aa [2] d9 aa [2] e6 b6 }

  condition:
    any of them
}