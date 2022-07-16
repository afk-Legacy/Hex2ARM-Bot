import discord
from discord.ext import commands
from discord_ui import UI , Button, Interaction
from keystone import keystone_const as ksconst

from asyncio import sleep as asleep
from convertor import b64_convert
from help import getHelp
from helper import get_Author, findURL, translateURL


# permissions integer: 534723951680
bot = commands.Bot(command_prefix='.')
ui = UI(bot)

@bot.event
async def on_message(message):
    ctx = await bot.get_context(message)
    author = get_Author(ctx)
    msg, hasURL = findURL(message)

    # Dont reply to self, bots
    if ctx.author.bot:
        return

    # Nothing in DMs
    if ctx.guild == None:
        await bot.process_commands(message)
        return
    
    # Dont respond to normal messages
    if not hasURL:
        await bot.process_commands(message)
        return
    
    embed = discord.Embed(title=f"", description=msg, colour=discord.Colour.green())
    embed.set_author(name = ctx.author, icon_url=author[1])
    embed.set_footer(text = "Links are encoded.")
        
    if message.reference is not None:
        # Fetching the message
        channel = bot.get_channel(message.reference.channel_id)
        referenced_message = await channel.fetch_message(message.reference.message_id)
            
        await ui.components.send(channel=message.channel,embed=embed, 
                                reference=message.reference, 
                                mention_author= referenced_message.author.mentioned_in(message),
                                components=[Button("Decode Links", "translate", "green")])
            
    else:
        await(ui.components.send(channel=message.channel, embed = embed,
                                components=[Button("Decode Links", "translate", "green")]))

        await message.delete()
    
    
    await bot.process_commands(message)

@bot.listen("on_interaction_received")
async def on_interact(interaction: Interaction):
    # See if translate button is clicked
    if interaction.data["custom_id"] == 'translate':
        msg = interaction.message
        embed = msg.embeds[0]
        links = translateURL(embed.description)
        await interaction.respond(content="**Links:**\n```\n" + links + "```", hidden=True)
    
@bot.command()
async def sh(ctx, task, string=None):
    username = get_Author(ctx)[0]

    if task == 'encode':
        embed = discord.Embed(title=f"Encoded string for {username}:", description=b64_convert(string, False), colour=discord.Colour.green())
        await ctx.send(embed=embed)

    elif task == 'decode':
        embed = discord.Embed(title=f"Decoded string for {username}:", description=b64_convert(string, True), colour=discord.Colour.green())
        await ctx.send(embed=embed)

    elif task == 'help':
        embed = discord.Embed(title="List of commands:", description=getHelp(), colour=discord.Colour.green())
        await ctx.send(embed=embed)

    else:
        embed = discord.Embed(title="List of commands:", description=getHelp(), colour=discord.Colour.green())
        await ctx.send(embed=embed)

@bot.event
async def on_ready():
    await bot.change_presence(activity = discord.Activity(name="Trying to Dream", type=discord.ActivityType.custom))
    print("Bot is ready!")

bot.load_extension("cogs.asm")
bot.run("MY BOT TOKEN")
