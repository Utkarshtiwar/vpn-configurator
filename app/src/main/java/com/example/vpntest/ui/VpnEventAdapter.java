package com.example.vpntest.ui;

import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.vpntest.R;
import com.example.vpntest.model.VpnEvent;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

public class VpnEventAdapter extends RecyclerView.Adapter<VpnEventAdapter.EventViewHolder> {


    private static final int MAX_ENTRIES = 3000;

    private final ArrayDeque<VpnEvent> events = new ArrayDeque<>();

    public void addEvent(VpnEvent event) {
        events.addLast(event);
        int insertedIndex = events.size() - 1;

        if (events.size() > MAX_ENTRIES) {
            events.removeFirst();


            notifyItemRemoved(0);
            insertedIndex--;
        }
        notifyItemInserted(insertedIndex);
    }

    public int getLastIndex() {
        return events.size() - 1;
    }

    @NonNull
    @Override
    public EventViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_vpn_event, parent, false);
        return new EventViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull EventViewHolder holder, int position) {

        List<VpnEvent> snapshot = new ArrayList<>(events);
        holder.bind(snapshot.get(position));
    }

    @Override
    public int getItemCount() {
        return events.size();
    }

    static class EventViewHolder extends RecyclerView.ViewHolder {
        private final ImageView icon;
        private final TextView message;
        private final TextView timestamp;

        EventViewHolder(@NonNull View itemView) {
            super(itemView);
            icon = itemView.findViewById(R.id.ivEventIcon);
            message = itemView.findViewById(R.id.tvEventMessage);
            timestamp = itemView.findViewById(R.id.tvEventTimestamp);
        }

        void bind(VpnEvent event) {
            message.setText(event.message);
            timestamp.setText(DateFormat.format("HH:mm:ss", event.timestampMillis));

            int colorRes;
            int iconRes;

            switch (event.category) {
                case TCP:
                    iconRes = R.drawable.ic_tcp;
                    colorRes = R.color.status_success;
                    break;
                case UDP:
                    iconRes = R.drawable.ic_udp;
                    colorRes = R.color.status_info;
                    break;
                case IPV6_SKIPPED:
                    iconRes = R.drawable.ic_warning;
                    colorRes = R.color.status_warning;
                    break;
                case ERROR:
                    iconRes = R.drawable.ic_error;
                    colorRes = R.color.status_error;
                    break;
                case MATCH:
                    iconRes = R.drawable.ic_search;
                    colorRes = R.color.status_error;
                    break;
                default:
                    iconRes = levelIcon(event.level);
                    colorRes = levelColor(event.level);
            }

            icon.setImageResource(iconRes);
            int color = itemView.getContext().getColor(colorRes);
            icon.setColorFilter(color);
            message.setTextColor(color);
        }

        private int levelIcon(VpnEvent.Level level) {
            switch (level) {
                case SUCCESS: return R.drawable.ic_success;
                case WARNING: return R.drawable.ic_warning;
                case ERROR: return R.drawable.ic_error;
                case INFO:
                default: return R.drawable.ic_info;
            }
        }
        private int levelColor(VpnEvent.Level level) {
            switch (level) {
                case SUCCESS: return R.color.status_success;
                case WARNING: return R.color.status_warning;
                case ERROR: return R.color.status_error;
                case INFO:
                default: return R.color.status_info;
            }
        }
    }
}