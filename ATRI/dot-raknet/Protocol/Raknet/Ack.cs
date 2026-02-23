using System.Collections.Generic;

public class AckRange
{
    public uint Start { get; set; }
    public uint End { get; set; }

    public AckRange(uint start, uint end)
    {
        Start = start;
        End = end;
    }
}

public class ACKSet
{
    private List<AckRange> ack;
    private List<AckRange> nack;
    private uint last_max;

    public ACKSet()
    {
        ack = new List<AckRange>();
        nack = new List<AckRange>();
        last_max = 0;
    }

    private Lock ackLock = new Lock();
    private Lock nackLock = new Lock();

    public void Insert(uint s)
    {
        if (s != 0)
        {
	        using (ackLock.EnterScope())
	        {
				if (s > last_max && s != last_max + 1)
				{
					using (nackLock.EnterScope())
					{
						nack.Add(new AckRange(last_max + 1, s - 1));
					}
				}

				if (s > last_max)
				{
					last_max = s;
				}
				if (ack.Count > 0)
				{
					for (int i = 0; i < ack.Count; i++)
					{
						AckRange a = ack[i];
						if (a != null)
						{
							if (a.Start != 0 && s == a.Start - 1)
							{
								ack.Insert(i, new AckRange(s, a.End));
								return;
							}
							if (s == a.End + 1)
							{
								ack.Insert(i, new AckRange(a.Start, s));
								return;
							}
						}
					}
				}
				ack.Add(new AckRange(s, s));
			}
        }
    }

    public List<AckRange> GetAck()
    {
		using (ackLock.EnterScope())
		{
            var ret = new List<AckRange>(ack);
            ack.Clear();
            return ret;
        }
    }

    public List<AckRange> GetNack()
    {
		using (ackLock.EnterScope())
		{
            var ret = new List<AckRange>(nack);
            nack.Clear();
            return ret;
        }
    }
}