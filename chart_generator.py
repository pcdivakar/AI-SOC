import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

def create_bar_chart(df, x_col, y_col=None, title=None):
    """Create a bar chart using plotly."""
    if y_col is None:
        # Count occurrences of x_col
        counts = df[x_col].value_counts().reset_index()
        counts.columns = [x_col, 'count']
        fig = px.bar(counts, x=x_col, y='count', title=title or f'Count of {x_col}')
    else:
        fig = px.bar(df, x=x_col, y=y_col, title=title or f'{y_col} by {x_col}')
    return fig

def create_pie_chart(df, names_col, values_col=None, title=None):
    """Create a pie chart."""
    if values_col is None:
        counts = df[names_col].value_counts().reset_index()
        counts.columns = [names_col, 'count']
        fig = px.pie(counts, names=names_col, values='count', title=title or f'Distribution of {names_col}')
    else:
        fig = px.pie(df, names=names_col, values=values_col, title=title or f'{values_col} by {names_col}')
    return fig

def create_line_chart(df, x_col, y_col, title=None):
    """Create a line chart."""
    fig = px.line(df, x=x_col, y=y_col, title=title or f'{y_col} over {x_col}')
    return fig

def create_heatmap(df, x_col, y_col, z_col, title=None):
    """Create a heatmap (requires aggregation)."""
    # Pivot table
    pivot = df.pivot_table(index=y_col, columns=x_col, values=z_col, aggfunc='mean')
    fig = px.imshow(pivot, text_auto=True, aspect="auto", title=title or f'Heatmap of {z_col}')
    return fig

def create_scatter_chart(df, x_col, y_col, color_col=None, title=None):
    """Create a scatter plot."""
    fig = px.scatter(df, x=x_col, y=y_col, color=color_col, title=title or f'{y_col} vs {x_col}')
    return fig

def generate_chart(chart_type, data, **kwargs):
    """
    Dispatch chart creation based on type.
    chart_type: 'bar', 'pie', 'line', 'heatmap', 'scatter'
    data: pandas DataFrame
    kwargs: additional parameters like x, y, title
    """
    if chart_type == 'bar':
        return create_bar_chart(data, **kwargs)
    elif chart_type == 'pie':
        return create_pie_chart(data, **kwargs)
    elif chart_type == 'line':
        return create_line_chart(data, **kwargs)
    elif chart_type == 'heatmap':
        return create_heatmap(data, **kwargs)
    elif chart_type == 'scatter':
        return create_scatter_chart(data, **kwargs)
    else:
        return None