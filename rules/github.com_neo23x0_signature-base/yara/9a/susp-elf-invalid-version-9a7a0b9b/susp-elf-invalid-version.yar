rule SUSP_ELF_Invalid_Version {
   meta:
      desc = "Identify ELF file that has mangled header info."
      author = "@shellcromancer"
      version = "0.1"
      score = 55
      last_modified = "2023.01.01"
      reference = "https://n0.lol/ebm/1.html"
      reference = "https://tmpout.sh/1/1.html"
      hash = "05379bbf3f46e05d385bbd853d33a13e7e5d7d50"
      id = "5bd97fdd-0912-5f9b-877c-91fff9b98dea"
   condition:
      (
         uint32(0) == 0x464c457f
         and uint8(0x6) > 1       )
}