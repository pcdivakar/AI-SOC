import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# Professional, vibrant color palettes (Big 4 style)
COLOR_PALETTES = {
    'bar': px.colors.qualitative.Pastel,
    'pie': px.colors.qualitative.Set3,
    'line': px.colors.qualitative.Dark2,
    'scatter': px.colors.qualitative.Vivid,
    'area': px.colors.qualitative.Plotly,
    'heatmap': 'Blues',
    'default': px.colors.qualitative.Bold
}

def apply_layout(fig, title, x_title=None, y_title=None, height=500):
    """Apply consistent, professional layout to any chart."""
    fig.update_layout(
        title=dict(text=title, font=dict(size=20, color='#86BC25'), x=0.5),
        xaxis_title=x_title,
        yaxis_title=y_title,
        plot_bgcolor='#1E3A3A',
        paper_bgcolor='#0A2F2F',
        font=dict(color='white'),
        height=height,
        margin=dict(l=40, r=40, t=60, b=40),
        legend=dict(font=dict(color='white'), bgcolor='rgba(0,0,0,0)')
    )
    fig.update_xaxes(gridcolor='#2A4A4A', gridwidth=0.5, tickfont=dict(color='white'))
    fig.update_yaxes(gridcolor='#2A4A4A', gridwidth=0.5, tickfont=dict(color='white'))
    return fig

def create_bar_chart(df, x_col, y_col=None, title=None):
    if y_col is None:
        counts = df[x_col].value_counts().reset_index()
        counts.columns = [x_col, 'count']
        fig = px.bar(counts, x=x_col, y='count', color=x_col, color_discrete_sequence=COLOR_PALETTES['bar'])
    else:
        fig = px.bar(df, x=x_col, y=y_col, color=x_col, color_discrete_sequence=COLOR_PALETTES['bar'])
    return apply_layout(fig, title or f'Bar Chart of {x_col}', x_title=x_col, y_title='Count' if y_col is None else y_col)

def create_pie_chart(df, names_col, values_col=None, title=None):
    if values_col is None:
        counts = df[names_col].value_counts().reset_index()
        counts.columns = [names_col, 'count']
        fig = px.pie(counts, names=names_col, values='count', color=names_col, color_discrete_sequence=COLOR_PALETTES['pie'])
    else:
        fig = px.pie(df, names=names_col, values=values_col, color=names_col, color_discrete_sequence=COLOR_PALETTES['pie'])
    fig.update_traces(textposition='inside', textinfo='percent+label', hole=0.4)
    return apply_layout(fig, title or f'Pie Chart of {names_col}', height=450)

def create_line_chart(df, x_col, y_col, title=None):
    fig = px.line(df, x=x_col, y=y_col, markers=True, color_discrete_sequence=COLOR_PALETTES['line'])
    return apply_layout(fig, title or f'Line Chart of {y_col} over {x_col}', x_title=x_col, y_title=y_col)

def create_scatter_chart(df, x_col, y_col, color_col=None, title=None):
    if color_col:
        fig = px.scatter(df, x=x_col, y=y_col, color=color_col, color_discrete_sequence=COLOR_PALETTES['scatter'])
    else:
        fig = px.scatter(df, x=x_col, y=y_col, color_discrete_sequence=[COLOR_PALETTES['scatter'][0]])
    return apply_layout(fig, title or f'Scatter Plot of {y_col} vs {x_col}', x_title=x_col, y_title=y_col)

def create_histogram(df, column, bins=None, title=None):
    fig = px.histogram(df, x=column, nbins=bins or 30, color_discrete_sequence=[COLOR_PALETTES['bar'][0]])
    return apply_layout(fig, title or f'Distribution of {column}', x_title=column, y_title='Frequency')

def create_box_chart(df, column, group_col=None, title=None):
    if group_col:
        fig = px.box(df, x=group_col, y=column, color=group_col, color_discrete_sequence=COLOR_PALETTES['bar'])
    else:
        fig = px.box(df, y=column, color_discrete_sequence=[COLOR_PALETTES['bar'][0]])
    return apply_layout(fig, title or f'Box Plot of {column}', x_title=group_col if group_col else '', y_title=column)

def create_violin_chart(df, column, group_col=None, title=None):
    if group_col:
        fig = px.violin(df, x=group_col, y=column, box=True, color=group_col, color_discrete_sequence=COLOR_PALETTES['pie'])
    else:
        fig = px.violin(df, y=column, box=True, color_discrete_sequence=[COLOR_PALETTES['pie'][0]])
    return apply_layout(fig, title or f'Violin Plot of {column}', x_title=group_col if group_col else '', y_title=column)

def create_heatmap(df, x_col, y_col, z_col, title=None):
    pivot = df.pivot_table(index=y_col, columns=x_col, values=z_col, aggfunc='mean')
    fig = px.imshow(pivot, text_auto=True, aspect="auto", color_continuous_scale=COLOR_PALETTES['heatmap'])
    fig.update_layout(coloraxis_colorbar=dict(title=z_col, tickfont=dict(color='white')))
    return apply_layout(fig, title or f'Heatmap of {z_col}', x_title=x_col, y_title=y_col, height=600)

def create_density_heatmap(df, x_col, y_col, title=None):
    fig = px.density_heatmap(df, x=x_col, y=y_col, color_continuous_scale=COLOR_PALETTES['heatmap'])
    return apply_layout(fig, title or f'Density Heatmap of {x_col} vs {y_col}', x_title=x_col, y_title=y_col)

def create_area_chart(df, x_col, y_col, title=None):
    fig = px.area(df, x=x_col, y=y_col, color_discrete_sequence=COLOR_PALETTES['area'])
    return apply_layout(fig, title or f'Area Chart of {y_col} over {x_col}', x_title=x_col, y_title=y_col)

def create_bubble_chart(df, x_col, y_col, size_col, color_col=None, title=None):
    if color_col:
        fig = px.scatter(df, x=x_col, y=y_col, size=size_col, color=color_col,
                         color_discrete_sequence=COLOR_PALETTES['scatter'])
    else:
        fig = px.scatter(df, x=x_col, y=y_col, size=size_col, color_discrete_sequence=[COLOR_PALETTES['scatter'][0]])
    return apply_layout(fig, title or f'Bubble Chart: {size_col} sized by {x_col}/{y_col}', x_title=x_col, y_title=y_col)

def create_sunburst_chart(df, path, values=None, title=None):
    fig = px.sunburst(df, path=path, values=values, color_discrete_sequence=COLOR_PALETTES['pie'])
    return apply_layout(fig, title or 'Sunburst Chart', height=600)

def create_treemap_chart(df, path, values=None, title=None):
    fig = px.treemap(df, path=path, values=values, color_discrete_sequence=COLOR_PALETTES['bar'])
    return apply_layout(fig, title or 'Treemap', height=600)

def create_scatter_map(df, lat_col, lon_col, color_col=None, size_col=None, title=None):
    fig = px.scatter_geo(df, lat=lat_col, lon=lon_col, color=color_col, size=size_col,
                         projection="natural earth", color_continuous_scale=COLOR_PALETTES['heatmap'])
    return apply_layout(fig, title or 'Geospatial Map', height=600)

def create_choropleth(df, locations, locationmode, color_col, title=None):
    fig = px.choropleth(df, locations=locations, locationmode=locationmode, color=color_col,
                        color_continuous_scale=COLOR_PALETTES['heatmap'])
    return apply_layout(fig, title or 'Choropleth Map', height=600)

def generate_chart(chart_type, data, **kwargs):
    """Dispatch chart creation based on type with consistent styling."""
    chart_type = chart_type.lower()
    if chart_type == 'bar':
        return create_bar_chart(data, **kwargs)
    elif chart_type == 'pie':
        return create_pie_chart(data, **kwargs)
    elif chart_type == 'line':
        return create_line_chart(data, **kwargs)
    elif chart_type == 'scatter':
        return create_scatter_chart(data, **kwargs)
    elif chart_type == 'histogram':
        return create_histogram(data, **kwargs)
    elif chart_type == 'box':
        return create_box_chart(data, **kwargs)
    elif chart_type == 'violin':
        return create_violin_chart(data, **kwargs)
    elif chart_type == 'heatmap':
        return create_heatmap(data, **kwargs)
    elif chart_type == 'density_heatmap':
        return create_density_heatmap(data, **kwargs)
    elif chart_type == 'area':
        return create_area_chart(data, **kwargs)
    elif chart_type == 'bubble':
        return create_bubble_chart(data, **kwargs)
    elif chart_type == 'sunburst':
        return create_sunburst_chart(data, **kwargs)
    elif chart_type == 'treemap':
        return create_treemap_chart(data, **kwargs)
    elif chart_type == 'scatter_map':
        return create_scatter_map(data, **kwargs)
    elif chart_type == 'choropleth':
        return create_choropleth(data, **kwargs)
    else:
        return None
