rule TTP_XOR_WriteProcessMemory_8ccf {
  strings:
    $key_8ccf = { db bd [2] e9 9f [2] ef aa [2] c1 aa [2] fe b6 }

  condition:
    any of them
}