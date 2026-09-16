rule TTP_XOR_WriteProcessMemory_cdcf {
  strings:
    $key_cdcf = { 9a bd [2] a8 9f [2] ae aa [2] 80 aa [2] bf b6 }

  condition:
    any of them
}