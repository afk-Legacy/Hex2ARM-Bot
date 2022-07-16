import discord, re
from discord.ext import commands
from keystone import *
from capstone import *
from binascii import unhexlify

from helper import get_Author

# Mainly used when decorating output
arch_constants = {KS_ARCH_ARM : "ARM", KS_ARCH_ARM64 : "ARM64", KS_MODE_THUMB: "THUMB",
                  CS_ARCH_ARM : "ARM", CS_ARCH_ARM64 : "ARM64", CS_MODE_THUMB: "THUMB"}

class ASM(commands.Cog):
    
    def __init__(self, bot):
        self.bot = bot

    def get_help(self):
        return """**To Convert to HEX:**
               .asm "from"-"to" "data"\n
               
               **Examples:**\n
               **.asm arm-hex "mov r0, #1; bx lr"**\n
               **.asm thumb-hex "movs r0, #1; bx lr"**\n
               **.asm arm64-hex "mov x0, #1; ret"**\n
               **.asm hex-arm "0100A0E31EFF2FE1"**\n
               """


    # Convert an instruction to 
    # its hex counterpart using Keystone
    def ks_convert(self, data, arch, mode):
        result = ""
        try:
            ks = Ks(arch, mode)
            encoding, count = ks.asm(data)
    
            for i in encoding:
                result += "%02X " % i

        except Exception as e:
            # Append just the description of error,
            # not the error identifier  
            # Example: Error Description (Error_Identifier)
            return re.findall(r"(.*?).(?=\()", str(e))[0]
        
        return result    

    # Convert an assembled instruction in hex 
    # to its instruction counterpart using Capstone
    def cs_convert(self, data, arch, mode):
        result = ""
        try:
            # Format the output by removing any potenital spaces 
            # and encoding it in byte format (for capstone to modify)
            data = unhexlify(data.replace(" ", ""))

            md = Cs(arch, mode)
            for i in md.disasm(data, 0x0):
                # \n to break line after each dissassembled instruction
                result += "%s\t%s" % (i.mnemonic, i.op_str) + "\n" 

        except Exception as e:
            print(e)
            return "An error was encountered, please refer to help using .asm help."

        return result

    # Return the result of conversion in a decorated embed form 
    def embed_result(self, ctx, data, arch, mode, convtype):
        username = get_Author(ctx)[0]
        embed_title = ""

        # 0 for assembling of data (ARM 2 Hex etc)
        if convtype == 0:
            
            if mode == KS_MODE_THUMB:
                embed_title = f"{arch_constants[mode]} to Hex Conversion"
            else:
                embed_title = f"{arch_constants[arch]} to Hex Conversion"

            embed = discord.Embed(title=embed_title, description=f"Requested by **{username}**", colour=discord.Colour.green())
            for code in data.split(";"):
                conversion = self.ks_convert(code, arch, mode)
                embed.add_field(name=code.upper(), value=conversion, inline=False)
            embed.set_footer(text = "Powered by Keystone")
            
            return embed

        # For disassembling of data (HEX 2 ARM etc)
        else:
            
            if mode == CS_MODE_THUMB:
                embed_title = f"Hex to {arch_constants[mode]} Conversion"
            else:
                embed_title = f"Hex to {arch_constants[arch]} Conversion"
            
                embed = discord.Embed(title=embed_title, description=f"Requested by **{username}**", colour=discord.Colour.green())
                conversion = self.cs_convert(data, arch, mode)
                embed.add_field(name=data.upper(), value=conversion.upper(), inline=False)
                embed.set_footer(text = "Powered by Capstone")
            
            return embed

    @commands.command()
    async def asm(self, ctx, task, string=None):
        
            choice = { 'arm-hex' : (KS_ARCH_ARM, KS_MODE_ARM, 0),
                       'arm64-hex' : (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, 0),
                       'thumb-hex' : (KS_ARCH_ARM, KS_MODE_THUMB, 0),
                       'hex-arm' :  (CS_ARCH_ARM, CS_MODE_ARM, 1),
                       'hex-arm64' : (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, 1),
                       'hex-thumb' : (CS_ARCH_ARM, CS_MODE_THUMB, 1)
                     }

            await ctx.send(embed = self.embed_result(ctx, string, choice.get(task)[0], choice.get(task)[1], choice.get(task)[2]))
            
def setup(bot):
    bot.add_cog(ASM(bot))
    