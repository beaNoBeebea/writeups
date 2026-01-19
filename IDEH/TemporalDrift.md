# TemporalDrift - IDEH 2026 Writeup

**Category:** [[Web]]   
**Flag:** `IDEH{t1m3_1s_r3l4t1v3_bu7_n07_c0n5t4n7}`

## Challenge Overview

This was one of the easiest challenges of IDEH2026.

The "Temporal Alignment Research Facility" presents a web interface that checks for "temporal drift" which is defined as the time gap between a certain moment in the 1980s and my current time. The goal is to provide a timestamp (`client_time`) that matches this hidden target time within a 300-second window.

## Discovery and Analysis

From the jump, we can see that we are given the value of the drift on the website:

![[website_TemporalDrift.png]]

A quick look into the client-side source code reveals how the application communicates with the backend:

```js
(function() {
    function refresh() {
        const now = Math.floor(Date.now() / 1000); // seconds since the epoch
        fetch(`/timecheck?client_time=${now}`)
            .then(r => r.json())
            .then(data => {
                document.getElementById("status").textContent = data.message;
                if (data.drift !== null) {
                    document.getElementById("driftbox").textContent =
                        "Drift Margin: " + data.drift.toLocaleString() + " seconds";
                }
                // ... logic for instability warnings
            });
    }
    // run immediately
    refresh();
    // refresh drift every 5 seconds as the timeline shifts every minute
    setInterval(refresh, 5000);
})();
```

The **`Date.now()`** static method returns the number of milliseconds elapsed since the _epoch_, which is defined as the midnight at the beginning of January 1, 1970, UTC.

The vulnerability lies in the mathematical transparency of the drift calculation. The server likely performs a simple subtraction:

$$
drift=∣TargetTimestamp−ClientTimestamp∣
$$

If we set our ClientTimestamp to **0** (the Unix Epoch), the formula becomes:

$$
drift=∣TargetTimestamp−0∣
$$

And the TargetTimestamp is guaranteed to be positive as it is in the 1980s (well after the epoch).

$$
drift=TargetTimestamp
$$

By sending `0`, the server's response will literally tell us the exact secret timestamp.

## Exploitation Path

### 1. Calculating the Target

This could be done through the console or by directly accessing the URL `https://ideh-temporaldrift.chals.io/timecheck?client_time=0` and verifying the response.

![[solving_TemporalDrift.png]]

The server returned a drift of **437,067,893**. This is our target timestamp.

### 2. Synchronizing the Timeline

With the calculated target time, I immediately sent a final request using that static value to zero out the drift (`https://ideh-temporaldrift.chals.io/timecheck?client_time=437067893`) :

![[solved_TemporalDrift.png]]

Since the drift is 0 (well within the 300-second allowance), I server returns the hidden message which contains the flag.

This will always work as long as I don't send the second request too late (after 300 seconds).

## Results

The server confirmed the synchronization and returned the flag:

- **Message:** `Timeline synchronized.`
- **Flag:** `IDEH{t1m3_1s_r3l4t1v3_bu7_n07_c0n5t4n7}`

## Conclusion

The vulnerability was an **Information Leak**. By exposing the numerical difference between the user input and the secret target, the server allowed for a simple mathematical calculation to reveal the "hidden" value.


[[IDEH2026]]