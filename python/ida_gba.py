# shared library for gba rom
# by laqieer
# 2018-10-01

from idc import *

def get_game_title():
    """
    Get title of game
    """
    return get_bytes(0x80000A0,12)

def get_game_code():
    """
    Get code of game
    This is the same code as the AGB-UTTD code which is printed on the package and sticker on (commercial) cartridges (excluding the leading "AGB-" part).
      U  Unique Code          (usually "A" or "B" or special meaning)
      TT Short Title          (eg. "PM" for Pac Man)
      D  Destination/Language (usually "J" or "E" or "P" or specific language)
    The first character (U) is usually "A" or "B", in detail:
      A  Normal game; Older titles (mainly 2001..2003)
      B  Normal game; Newer titles (2003..)
      C  Normal game; Not used yet, but might be used for even newer titles
      F  Famicom/Classic NES Series (software emulated NES games)
      K  Yoshi and Koro Koro Puzzle (acceleration sensor)
      P  e-Reader (dot-code scanner)
      R  Warioware Twisted (cartridge with rumble and z-axis gyro sensor)
      U  Boktai 1 and 2 (cartridge with RTC and solar sensor)
      V  Drill Dozer (cartridge with rumble)
    The second/third characters (TT) are:
      Usually an abbreviation of the game title (eg. "PM" for "Pac Man") (unless
      that gamecode was already used for another game, then TT is just random)
    The fourth character (D) indicates Destination/Language:
      J  Japan             P  Europe/Elsewhere   F  French          S  Spanish
      E  USA/English       D  German             I  Italian
    """
    return get_bytes(0x80000AC,4)

def get_maker_code():
    """
    Get maker code in cartridge header
    Identifies the (commercial) developer. For example, "01"=Nintendo.
    """
    return get_bytes(0x80000B0,2)

def get_software_version():
    """
    Get software version in cartridge header
    Version number of the game. Usually zero.
    """
    return get_byte(0x80000BC)

def get_header_checksum():
    """
    Get checksum of cartridge header
    """
    return get_byte(0x80000BD)
