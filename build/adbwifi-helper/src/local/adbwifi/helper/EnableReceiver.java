// SPDX-License-Identifier: GPL-3.0-only
package local.adbwifi.helper;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Settings;
import android.util.Log;

public class EnableReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        try {
            Settings.Global.putInt(context.getContentResolver(), "adb_wifi_enabled", 1);
            Settings.Global.putInt(context.getContentResolver(), Settings.Global.ADB_ENABLED, 1);
            Settings.Global.putLong(context.getContentResolver(), "adb_allowed_connection_time", 0L);
            Log.i("AdbWifiHelper", "SUCCESS: adb_wifi_enabled set via receiver");
        } catch (Throwable t) {
            Log.e("AdbWifiHelper", "FAILED: " + t, t);
        }
    }
}
