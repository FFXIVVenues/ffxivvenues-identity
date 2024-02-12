﻿namespace FFXIVVenues.Identity.Helpers;

public static class IdHelper
{
    public static string GenerateId(int length = 12)
    {
        var chars = "BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789_-%*";
        var stringChars = new char[length];
        var random = new Random();

        for (int i = 0; i < stringChars.Length; i++)
        {
            stringChars[i] = chars[random.Next(chars.Length)];
        }

        return new string(stringChars);
    }

}