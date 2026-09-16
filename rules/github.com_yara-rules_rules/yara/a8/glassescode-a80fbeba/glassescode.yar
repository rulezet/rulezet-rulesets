rule GlassesCode : Glasses Family 
{
    meta:
        description = "Glasses code features"
        author = "Seth Hardy"
        last_modified = "2021-11-18"
        reference_file = "aaf262fde1738dbf0bb50213a9624cd6705ebcaeb06c5fcaf7e9f33695d3fc33"
        reference_url = "https://citizenlab.ca/2013/02/apt1s-glasses-watching-a-human-rights-organization/"

        
    strings:
        $ = { B8 AB AA AA AA F7 E1 D1 EA 8D 04 52 2B C8 }
        $ = { B8 56 55 55 55 F7 E9 8B 4C 24 1C 8B C2 C1 E8 1F 03 D0 49 3B CA }
        
    condition:
        any of them
}