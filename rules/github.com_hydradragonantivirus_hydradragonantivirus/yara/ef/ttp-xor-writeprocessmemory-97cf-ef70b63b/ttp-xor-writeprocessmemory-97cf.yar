rule TTP_XOR_WriteProcessMemory_97cf {
  strings:
    $key_97cf = { c0 bd [2] f2 9f [2] f4 aa [2] da aa [2] e5 b6 }

  condition:
    any of them
}